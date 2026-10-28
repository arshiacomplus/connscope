import argparse
import asyncio
from dataclasses import replace
from enum import IntEnum
import json
import os
import sys
from typing import Any, Mapping, TextIO

from connscope.agent import (
    DEFAULT_CLIENT_TIMEOUT_S,
    ClientConfigurationError,
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemoteClientError,
    RemoteConnectionError,
    RemoteHttpError,
    RemotePolicyError,
    RemoteProtocolError,
    RemoteRedirectError,
    RemoteTimeoutError,
    RemoteUnavailableError,
)
from connscope.core import ProbeEngine, ProbeRegistry, ProbeStatus, Target
from connscope.probes import register_builtin_probes
from connscope.cli.output import (
    render_error,
    render_probe_list,
    render_result,
    render_result_json,
)
from connscope.cli.parse import (
    PROBE_ALIASES,
    parse_http_target,
    parse_target,
    resolve_probe_name,
    validate_timeout,
)
from connscope.probes._utils import validate_sni
from connscope.scenarios import (
    DEFAULT_DIAGNOSTIC_UUID,
    FailurePolicy,
    GenerationMode,
    LocalDiagnosticHarness,
    MatrixExecutionResult,
    MatrixExecutionSummary,
    MatrixPlan,
    MatrixSizeExceededError,
    MeasurementNode,
    MeasurementWorkload,
    ProtocolCatalog,
    Scenario,
    ScenarioCoordinator,
    ScenarioGenerator,
    VerificationStatus,
    create_default_protocol_catalog,
    detect_local_engine_versions,
    evaluate_parameter_coverage,
    generate_coverage_report,
    render_catalog_summary,
    render_coverage_json,
    render_coverage_table,
    render_execution_summary_json,
    render_execution_summary_table,
    render_parameter_coverage_json,
    render_parameter_coverage_table,
    render_scenario_matrix_json,
    render_scenario_matrix_table,
    write_jsonl,
)

try:
    from importlib.metadata import version
    __version__ = version("connscope")
except Exception:
    __version__ = "0.1.0"

class ExitCode(IntEnum):
    OK = 0
    FAILED = 1
    TIMEOUT = 2
    USAGE_ERROR = 3
    INTERNAL_ERROR = 4

STATUS_TO_EXIT_CODE: dict[ProbeStatus, ExitCode] = {
    ProbeStatus.SUCCESS: ExitCode.OK,
    ProbeStatus.FAILED: ExitCode.FAILED,
    ProbeStatus.TIMEOUT: ExitCode.TIMEOUT,
}

class UsageError(Exception):
    pass

class ArgumentParserExit(Exception):
    def __init__(self, status: int, message: str | None = None) -> None:
        self.status = status
        self.message = message

class ConnScopeParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, stdout: TextIO | None = None, stderr: TextIO | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._custom_stdout = stdout
        self._custom_stderr = stderr

    def _get_stdout(self) -> TextIO:
        return self._custom_stdout if self._custom_stdout is not None else sys.stdout

    def _get_stderr(self) -> TextIO:
        return self._custom_stderr if self._custom_stderr is not None else sys.stderr

    def _print_message(self, message: str, file: Any = None) -> None:
        if not message:
            return
        if file is None or file is sys.stdout:
            target = self._get_stdout()
        elif file is sys.stderr:
            target = self._get_stderr()
        else:
            target = file
        target.write(message)

    def print_usage(self, file: TextIO | None = None) -> None:
        super().print_usage(file or self._get_stderr())

    def print_help(self, file: TextIO | None = None) -> None:
        super().print_help(file or self._get_stdout())

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if message:
            self._print_message(message, sys.stderr if status != 0 else sys.stdout)
        raise ArgumentParserExit(status, message)

    def error(self, message: str) -> None:
        self.print_usage(self._get_stderr())
        raise UsageError(message)

def create_default_registry() -> ProbeRegistry:
    registry = ProbeRegistry()
    register_builtin_probes(registry)
    return registry

def build_parser(stdout: TextIO | None = None, stderr: TextIO | None = None) -> ConnScopeParser:
    parser = ConnScopeParser(
        prog="connscope",
        description="ConnScope — Network Measurement & Connectivity Monitoring Framework",
        stdout=stdout,
        stderr=stderr,
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"connscope {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    probe_parser = subparsers.add_parser("probe", help="Probe commands")
    probe_sub = probe_parser.add_subparsers(dest="probe_command")
    probe_sub.add_parser("list", help="List available builtin probes")

    subparsers.add_parser("list", help="List available builtin probes")

    run_parser = subparsers.add_parser("run", help="Run a probe against a target")
    run_parser.add_argument("probe", help="Probe name or alias (e.g. tcp, dns, tls, http)")
    run_parser.add_argument("target", help="Target address, host:port, or HTTP URL")
    run_parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Probe timeout in seconds",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output measurement result as JSON",
    )
    run_parser.add_argument(
        "--node",
        metavar="URL",
        default=None,
        help="Remote Agent base URL (overrides CONNSCOPE_AGENT_URL)",
    )
    run_parser.add_argument(
        "--token",
        metavar="TOKEN",
        default=None,
        help=(
            "Remote Agent Bearer token (overrides CONNSCOPE_AGENT_TOKEN). "
            "Note: Environment variable CONNSCOPE_AGENT_TOKEN is recommended "
            "to avoid exposing tokens in process listings."
        ),
    )
    sni_group = run_parser.add_mutually_exclusive_group()
    sni_group.add_argument(
        "--sni",
        metavar="HOST",
        default=None,
        help="Explicit TLS Server Name Indication (SNI) hostname",
    )
    sni_group.add_argument(
        "--no-sni",
        action="store_true",
        default=False,
        help="Omit TLS Server Name Indication (SNI) extension",
    )
    run_parser.add_argument(
        "--config",
        metavar="JSON_OR_PATH",
        default=None,
        help="Probe configuration as JSON string or path to JSON file",
    )

    catalog_parser = subparsers.add_parser("catalog", help="Declarative protocol and engine catalog commands")
    catalog_sub = catalog_parser.add_subparsers(dest="catalog_command")

    cat_val = catalog_sub.add_parser("validate", help="Validate catalog schema and consistency")
    cat_val.add_argument("path", nargs="?", default=None, help="Optional path to custom catalog JSON file")
    cat_val.add_argument("--json", action="store_true", default=False, help="Output validation result as JSON")

    cat_list = catalog_sub.add_parser("list", help="List engines and protocol profiles in the catalog")
    cat_list.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    cat_list.add_argument("--json", action="store_true", default=False, help="Output catalog as JSON")

    cat_show = catalog_sub.add_parser("show", help="Show details for an engine or protocol profile")
    cat_show.add_argument("id", help="Engine ID or Protocol Profile ID")
    cat_show.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    cat_show.add_argument("--json", action="store_true", default=False, help="Output details as JSON")

    cat_cov = catalog_sub.add_parser("coverage", help="Display capability and parameter coverage report")
    cat_cov.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    cat_cov.add_argument("--engine", default=None, help="Filter coverage report by engine ID")
    cat_cov.add_argument("--protocol", default=None, help="Filter coverage report by protocol")
    cat_cov.add_argument("--category", default=None, help="Filter coverage report by taxonomy category")
    cat_cov.add_argument("--json", action="store_true", default=False, help="Output coverage report as JSON")

    cat_param_cov = catalog_sub.add_parser("parameter-coverage", help="Display per-profile parameter-space coverage report")
    cat_param_cov.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    cat_param_cov.add_argument("--engine", default=None, help="Filter coverage report by engine ID")
    cat_param_cov.add_argument("--profile", default=None, help="Filter coverage report by profile ID")
    cat_param_cov.add_argument("--validate-binary", action="store_true", default=False, help="Run real-binary validation on parameter test configurations")
    cat_param_cov.add_argument("--json", action="store_true", default=False, help="Output coverage report as JSON")

    cat_check = catalog_sub.add_parser("check", help="Check local environment readiness for executable protocol engines")
    cat_check.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    cat_check.add_argument("--json", action="store_true", default=False, help="Output environment check as JSON")

    matrix_parser = subparsers.add_parser("matrix", help="Scenario matrix generation and preview")
    matrix_sub = matrix_parser.add_subparsers(dest="matrix_command")

    mat_prev = matrix_sub.add_parser("preview", help="Preview planned scenario matrix without executing")
    mat_prev.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    mat_prev.add_argument("--engine", default=None, help="Filter or specify engine ID (e.g. xray, sing_box)")
    mat_prev.add_argument("--profile", default=None, help="Filter or specify protocol profile ID")
    mat_prev.add_argument("--variant", default=None, help="Filter or specify variant ID")
    mat_prev.add_argument(
        "--mode",
        choices=["explicit", "ofat", "pairwise", "exhaustive"],
        default="explicit",
        help="Matrix generation strategy (default: explicit)",
    )
    mat_prev.add_argument("--target", default="127.0.0.1:443", help="Target address host:port (default: 127.0.0.1:443)")
    mat_prev.add_argument("--node", default=None, help="Measurement node ID (default: local)")
    mat_prev.add_argument(
        "--config",
        metavar="JSON_OR_PATH",
        default=None,
        help="Scenario parameter overrides as JSON string or path to JSON file",
    )
    mat_prev.add_argument("--test-url", default=None, help="Application test URL (default: http://cp.cloudflare.com/generate_204)")
    mat_prev.add_argument(
        "--local-diagnostic",
        action="store_true",
        default=False,
        help="Plan execution using isolated local loopback diagnostic harness",
    )
    mat_prev.add_argument("--max-scenarios", type=int, default=100, help="Maximum allowed scenarios (default: 100)")
    mat_prev.add_argument(
        "--allow-exhaustive",
        action="store_true",
        default=False,
        help="Explicitly permit large exhaustive Cartesian matrices",
    )
    mat_prev.add_argument("--json", action="store_true", default=False, help="Output matrix preview as JSON")

    mat_est = matrix_sub.add_parser("estimate", help="Estimate scenario count before generating")
    mat_est.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    mat_est.add_argument("--engine", default=None, help="Filter or specify engine ID")
    mat_est.add_argument("--profile", default=None, help="Filter or specify protocol profile ID")
    mat_est.add_argument("--variant", default=None, help="Filter or specify variant ID")
    mat_est.add_argument(
        "--mode",
        choices=["explicit", "ofat", "pairwise", "exhaustive"],
        default="explicit",
        help="Matrix generation strategy (default: explicit)",
    )
    mat_est.add_argument("--json", action="store_true", default=False, help="Output estimate as JSON")

    mat_run = matrix_sub.add_parser("run", help="Execute scenario matrix measurements through local adapters")
    mat_run.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    mat_run.add_argument("--engine", default=None, help="Filter or specify engine ID (e.g. xray, sing_box)")
    mat_run.add_argument("--profile", default=None, help="Filter or specify protocol profile ID")
    mat_run.add_argument("--variant", default=None, help="Filter or specify variant ID")
    mat_run.add_argument(
        "--mode",
        choices=["explicit", "ofat", "pairwise", "exhaustive"],
        default="explicit",
        help="Matrix generation strategy (default: explicit)",
    )
    mat_run.add_argument("--target", default="127.0.0.1:443", help="Target address host:port (default: 127.0.0.1:443)")
    mat_run.add_argument("--node", default=None, help="Measurement node ID (default: local)")
    mat_run.add_argument(
        "--config",
        metavar="JSON_OR_PATH",
        default=None,
        help="Scenario parameter overrides as JSON string or path to JSON file",
    )
    mat_run.add_argument("--test-url", default=None, help="Application test URL (default: http://cp.cloudflare.com/generate_204)")
    mat_run.add_argument(
        "--local-diagnostic",
        action="store_true",
        default=False,
        help="Execute scenario using isolated local loopback diagnostic harness (VLESS TCP None + HTTP 204)",
    )
    mat_run.add_argument("--repetitions", type=int, default=None, help="Repetitions count per scenario")
    mat_run.add_argument("--concurrency", type=int, default=1, help="Bounded concurrent adapter executions (default: 1)")
    mat_run.add_argument(
        "--failure-policy",
        choices=["continue", "stop"],
        default="continue",
        help="Policy on individual measurement failure: continue (default) or stop",
    )
    mat_run.add_argument("--max-scenarios", type=int, default=100, help="Maximum allowed scenarios (default: 100)")
    mat_run.add_argument(
        "--allow-exhaustive",
        action="store_true",
        default=False,
        help="Explicitly permit large exhaustive Cartesian matrices",
    )
    mat_run.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Explicit opt-in required to execute external adapter processes (defaults to dry-run planning)",
    )
    mat_run.add_argument(
        "--output-file",
        "--jsonl",
        dest="output_file",
        default=None,
        help="Output file path for JSON Lines measurement records",
    )
    mat_run.add_argument("--summary-file", default=None, help="Output file path for JSON execution summary")
    mat_run.add_argument("--json", action="store_true", default=False, help="Output summary as JSON")

    mat_cov = matrix_sub.add_parser("coverage", help="Display capability and parameter coverage report")
    mat_cov.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    mat_cov.add_argument("--engine", default=None, help="Filter coverage report by engine ID")
    mat_cov.add_argument("--protocol", default=None, help="Filter coverage report by protocol")
    mat_cov.add_argument("--category", default=None, help="Filter coverage report by taxonomy category")
    mat_cov.add_argument("--json", action="store_true", default=False, help="Output coverage report as JSON")

    mat_prev_param = matrix_sub.add_parser("preview-parameters", help="Preview planned parameter-space test scenarios")
    mat_prev_param.add_argument("--catalog", default=None, help="Optional path to custom catalog JSON file")
    mat_prev_param.add_argument("--engine", default="xray", help="Engine ID (default: xray)")
    mat_prev_param.add_argument("--profile", default="vless_tcp_reality", help="Profile ID (default: vless_tcp_reality)")
    mat_prev_param.add_argument("--strategy", choices=["ofat", "pairwise"], default="ofat", help="Strategy for parameter scenarios: ofat or pairwise (default: ofat)")
    mat_prev_param.add_argument("--target", default="127.0.0.1:443", help="Target address host:port (default: 127.0.0.1:443)")
    mat_prev_param.add_argument("--node", default=None, help="Measurement node ID (default: local)")
    mat_prev_param.add_argument("--include-invalid", action="store_true", default=False, help="Include invalid parameter test cases")
    mat_prev_param.add_argument("--validate-binary", action="store_true", default=False, help="Run real-binary parser validation on generated scenarios")
    mat_prev_param.add_argument("--json", action="store_true", default=False, help="Output scenarios as JSON")

    return parser

def resolve_remote_config(
    cli_node: str | None,
    cli_token: str | None,
    env: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    effective_env = env if env is not None else os.environ

    node: str | None = None
    if cli_node is not None:
        node = cli_node
    else:
        env_url = effective_env.get("CONNSCOPE_AGENT_URL")
        if env_url is not None and env_url.strip():
            node = env_url.strip()

    token: str | None = None
    if cli_token is not None:
        token = cli_token
    else:
        env_tok = effective_env.get("CONNSCOPE_AGENT_TOKEN")
        if env_tok is not None and env_tok.strip():
            token = env_tok.strip()

    return node, token

def format_remote_error(exc: RemoteClientError, token: str | None = None) -> str:
    msg: str
    if isinstance(exc, ClientConfigurationError):
        msg = str(exc)
    elif isinstance(exc, RemoteAuthenticationError):
        msg = f"Remote agent authentication failed (HTTP {exc.status_code})"
    elif isinstance(exc, RemotePolicyError):
        msg = f"Remote agent security policy rejected measurement (HTTP {exc.status_code})"
    elif isinstance(exc, RemoteUnavailableError):
        msg = f"Remote agent is currently unavailable (HTTP {exc.status_code})"
    elif isinstance(exc, RemoteTimeoutError):
        if exc.status_code:
            msg = f"Remote agent gateway timeout (HTTP {exc.status_code})"
        else:
            msg = str(exc)
    elif isinstance(exc, RemoteConnectionError):
        msg = str(exc)
    elif isinstance(exc, RemoteProtocolError):
        msg = f"Remote agent protocol error: {exc}"
    elif isinstance(exc, RemoteRedirectError):
        msg = f"Unexpected redirect received from remote agent (HTTP {exc.status_code})"
    elif isinstance(exc, RemoteHttpError):
        msg = f"Remote agent returned HTTP {exc.status_code}"
    else:
        msg = str(exc)

    if token and token in msg:
        msg = msg.replace(token, "[REDACTED]")
    return msg

def safe_render_error(message: str, token: str | None = None) -> str:
    rendered = render_error(message)
    if token and token in rendered:
        rendered = rendered.replace(token, "[REDACTED]")
    return rendered

def _dispatch(
    args: argparse.Namespace,
    out_stream: TextIO,
    err_stream: TextIO,
    registry: ProbeRegistry | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    reg = registry if registry is not None else create_default_registry()

    if args.command == "probe":
        if getattr(args, "probe_command", None) != "list":
            err_stream.write(render_error("Missing probe subcommand. Use 'connscope probe list'.") + "\n")
            return ExitCode.USAGE_ERROR
        out_stream.write(render_probe_list(reg.names(), PROBE_ALIASES) + "\n")
        return ExitCode.OK

    if args.command == "list":
        out_stream.write(render_probe_list(reg.names(), PROBE_ALIASES) + "\n")
        return ExitCode.OK

    if args.command == "run":
        node, token = resolve_remote_config(
            getattr(args, "node", None),
            getattr(args, "token", None),
            env=env,
        )

        if getattr(args, "node", None) is not None and not args.node.strip():
            err_stream.write(safe_render_error("Remote node URL cannot be empty.", token=token) + "\n")
            return ExitCode.USAGE_ERROR

        if getattr(args, "token", None) is not None and not args.token.strip():
            err_stream.write(safe_render_error("Remote authentication token cannot be empty.", token=token) + "\n")
            return ExitCode.USAGE_ERROR

        if node is not None and (token is None or not token.strip()):
            err_stream.write(
                safe_render_error(
                    "Remote node URL configured without an authentication token. "
                    "Please provide --token or set CONNSCOPE_AGENT_TOKEN.",
                    token=token,
                )
                + "\n"
            )
            return ExitCode.USAGE_ERROR

        if token is not None and (node is None or not node.strip()):
            err_stream.write(
                safe_render_error(
                    "Authentication token provided without a remote node URL. "
                    "Please provide --node or set CONNSCOPE_AGENT_URL.",
                    token=token,
                )
                + "\n"
            )
            return ExitCode.USAGE_ERROR

        try:
            canonical = resolve_probe_name(args.probe, reg)
        except KeyError as exc:
            err_stream.write(safe_render_error(str(exc), token=token) + "\n")
            return ExitCode.USAGE_ERROR

        try:
            if canonical == "http_request":
                target, config = parse_http_target(args.target)
            else:
                target = parse_target(args.target)
                config = {}
        except ValueError as exc:
            err_stream.write(safe_render_error(str(exc), token=token) + "\n")
            return ExitCode.USAGE_ERROR

        if getattr(args, "config", None) is not None:
            raw_cfg = args.config.strip()
            cfg_obj: dict[str, Any] = {}
            if os.path.isfile(raw_cfg):
                try:
                    with open(raw_cfg, "r", encoding="utf-8") as f:
                        cfg_obj = json.load(f)
                except Exception as exc:
                    err_stream.write(safe_render_error(f"Failed to read config file: {exc}", token=token) + "\n")
                    return ExitCode.USAGE_ERROR
            else:
                try:
                    cfg_obj = json.loads(raw_cfg)
                except Exception as exc:
                    err_stream.write(safe_render_error(f"Invalid JSON in --config: {exc}", token=token) + "\n")
                    return ExitCode.USAGE_ERROR
            if not isinstance(cfg_obj, dict):
                err_stream.write(safe_render_error("--config must resolve to a JSON object (dictionary)", token=token) + "\n")
                return ExitCode.USAGE_ERROR
            config.update(cfg_obj)

        if canonical == "tcp_connect" and target.port is None:
            err_stream.write(
                safe_render_error(
                    f"Target port is required for TCP probe: '{args.target}' (e.g. 'example.com:443')",
                    token=token,
                )
                + "\n"
            )
            return ExitCode.USAGE_ERROR

        if canonical == "dns_resolve" and target.port is not None:
            err_stream.write(
                safe_render_error(f"Port is not supported for DNS probe: '{args.target}'", token=token) + "\n"
            )
            return ExitCode.USAGE_ERROR

        if args.timeout is not None:
            try:
                config["timeout_s"] = validate_timeout(args.timeout)
            except ValueError as exc:
                err_stream.write(safe_render_error(str(exc), token=token) + "\n")
                return ExitCode.USAGE_ERROR

        if canonical != "tls_handshake":
            if getattr(args, "sni", None) is not None:
                err_stream.write(safe_render_error("--sni is only supported for the TLS probe", token=token) + "\n")
                return ExitCode.USAGE_ERROR
            if getattr(args, "no_sni", False):
                err_stream.write(safe_render_error("--no-sni is only supported for the TLS probe", token=token) + "\n")
                return ExitCode.USAGE_ERROR
        else:
            if getattr(args, "sni", None) is not None:
                try:
                    config["sni"] = validate_sni(args.sni)
                except ValueError as exc:
                    err_stream.write(safe_render_error(f"Invalid --sni hostname: {exc}", token=token) + "\n")
                    return ExitCode.USAGE_ERROR
            elif getattr(args, "no_sni", False):
                config["no_sni"] = True

        if node is not None and token is not None:
            client_timeout = (
                max(DEFAULT_CLIENT_TIMEOUT_S, float(args.timeout) + 5.0)
                if args.timeout is not None
                else DEFAULT_CLIENT_TIMEOUT_S
            )
            try:
                client = RemoteAgentClient(node_url=node, token=token, timeout_s=client_timeout)
                result = client.measure(canonical, target, config)
            except ClientConfigurationError as exc:
                err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
                return ExitCode.USAGE_ERROR
            except RemoteTimeoutError as exc:
                err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
                return ExitCode.TIMEOUT
            except RemoteClientError as exc:
                err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
                return ExitCode.FAILED
        else:
            engine = ProbeEngine(registry=reg)
            result = asyncio.run(engine.run(canonical, target, config))

        if getattr(args, "json", False):
            out_str = render_result_json(result)
        else:
            out_str = render_result(result)
        out_stream.write(out_str + "\n")
        return STATUS_TO_EXIT_CODE.get(result.status, ExitCode.INTERNAL_ERROR)

    if args.command == "catalog":
        cat_cmd = getattr(args, "catalog_command", None)
        if cat_cmd is None:
            err_stream.write(render_error("Missing catalog subcommand. Use 'connscope catalog validate', 'list', or 'show'.") + "\n")
            return ExitCode.USAGE_ERROR

        cat_path = getattr(args, "catalog", None) or getattr(args, "path", None)
        if cat_path:
            if not os.path.isfile(cat_path):
                err_stream.write(render_error(f"Catalog file not found: '{cat_path}'") + "\n")
                return ExitCode.USAGE_ERROR
            try:
                catalog = ProtocolCatalog.from_json_file(cat_path)
            except Exception as exc:
                err_stream.write(render_error(f"Failed to parse catalog JSON file: {exc}") + "\n")
                return ExitCode.USAGE_ERROR
        else:
            catalog = create_default_protocol_catalog()

        if cat_cmd == "validate":
            errors = catalog.validate_catalog()
            if getattr(args, "json", False):
                out_stream.write(
                    json.dumps(
                        {
                            "valid": len(errors) == 0,
                            "errors": errors,
                            "engines_count": len(catalog.list_engines()),
                            "profiles_count": len(catalog.list_profiles()),
                            "compatibilities_count": len(catalog.list_compatibilities()),
                        },
                        indent=2,
                    )
                    + "\n"
                )
            else:
                if errors:
                    err_stream.write(
                        render_error(f"Catalog validation failed with {len(errors)} error(s):\n" + "\n".join(f"  - {e}" for e in errors))
                        + "\n"
                    )
                else:
                    out_stream.write(
                        f"Catalog is valid ({len(catalog.list_engines())} engines, {len(catalog.list_profiles())} profiles, {len(catalog.list_compatibilities())} compatibility rules).\n"
                    )
            return ExitCode.OK if len(errors) == 0 else ExitCode.USAGE_ERROR

        if cat_cmd == "list":
            if getattr(args, "json", False):
                out_stream.write(json.dumps(catalog.to_dict(), indent=2) + "\n")
            else:
                out_stream.write(render_catalog_summary(catalog) + "\n")
            return ExitCode.OK

        if cat_cmd == "show":
            target_id = getattr(args, "id", "")
            eng = catalog.get_engine(target_id)
            prof = catalog.get_profile(target_id)
            if not eng and not prof:
                err_stream.write(render_error(f"Unknown engine or profile ID: '{target_id}'") + "\n")
                return ExitCode.USAGE_ERROR

            if getattr(args, "json", False):
                res: dict[str, Any] = {}
                if eng:
                    res["engine"] = eng.to_dict()
                if prof:
                    res["profile"] = prof.to_dict()
                out_stream.write(json.dumps(res, indent=2) + "\n")
            else:
                if eng:
                    out_stream.write(f"Engine: {eng.engine_id} ({eng.display_name})\n")
                    out_stream.write(f"Description: {eng.description}\n")
                    out_stream.write(f"Evidence Status: {eng.evidence_status.value}\n")
                    if eng.executable:
                        out_stream.write(f"Executable: {eng.executable.binary_name} (min version: {eng.executable.min_version})\n")
                    if eng.tested_versions:
                        out_stream.write(f"Tested Versions: {', '.join(eng.tested_versions)}\n")
                    if eng.source_reference:
                        if eng.source_reference.repository_url:
                            out_stream.write(f"Repository: {eng.source_reference.repository_url}\n")
                        if eng.source_reference.requires_source_confirmation:
                            out_stream.write(f"Source Confirmation Required: {eng.source_reference.notes}\n")
                if prof:
                    if eng:
                        out_stream.write("\n" + "-" * 40 + "\n")
                    out_stream.write(f"Profile: {prof.profile_id} ({prof.display_name})\n")
                    out_stream.write(f"Protocol/Transport/Security: {prof.protocol} / {prof.transport} / {prof.security}\n")
                    out_stream.write(f"Parameters ({len(prof.parameters)}):\n")
                    for p in prof.parameters:
                        sec = " [SECRET]" if p.is_secret else ""
                        req = " (required)" if p.required else f" (default: {p.default})"
                        out_stream.write(f"  - {p.param_id} ({p.param_type.value}){req}{sec}: {p.description}\n")
                    out_stream.write(f"Default Variants ({len(prof.default_variants)}):\n")
                    for v in prof.default_variants:
                        out_stream.write(f"  - {v.variant_id}: {v.description} (overrides: {v.overrides})\n")
            return ExitCode.OK

        if cat_cmd == "coverage":
            report = generate_coverage_report(
                catalog,
                engine_filter=getattr(args, "engine", None),
                protocol_filter=getattr(args, "protocol", None),
                category_filter=getattr(args, "category", None),
            )
            if getattr(args, "json", False):
                out_stream.write(render_coverage_json(report) + "\n")
            else:
                out_stream.write(render_coverage_table(report) + "\n")
            return ExitCode.OK

        if cat_cmd == "parameter-coverage":
            summary = evaluate_parameter_coverage(
                catalog,
                engine_filter=getattr(args, "engine", None),
                profile_filter=getattr(args, "profile", None),
                validate_binaries=getattr(args, "validate_binary", False),
            )
            if getattr(args, "json", False):
                out_stream.write(render_parameter_coverage_json(summary) + "\n")
            else:
                out_stream.write(render_parameter_coverage_table(summary) + "\n")
            return ExitCode.OK

        if cat_cmd == "check":
            versions = detect_local_engine_versions()
            from connscope.adapters import resolve_safe_executable
            from connscope.scenarios.parameter_coverage import EXECUTABLE_PROFILE_FAMILIES

            engine_status: dict[str, Any] = {}
            for eng in catalog.list_engines():
                exe_name = eng.executable.binary_name if eng.executable else None
                exe_path = resolve_safe_executable(exe_name) if exe_name else None
                ver = versions.get(eng.engine_id, "unknown")
                is_ready = bool(exe_path and ver not in ("unavailable", "unknown"))
                engine_status[eng.engine_id] = {
                    "display_name": eng.display_name,
                    "binary": exe_name,
                    "path": exe_path,
                    "version": ver,
                    "is_ready": is_ready,
                }

            profile_readiness: list[dict[str, Any]] = []
            for prof_id in EXECUTABLE_PROFILE_FAMILIES:
                prof = catalog.get_profile(prof_id)
                prof_name = prof.display_name if prof else prof_id
                xray_ready = engine_status.get("xray", {}).get("is_ready", False)
                sb_ready = engine_status.get("sing_box", {}).get("is_ready", False)
                profile_readiness.append({
                    "profile_id": prof_id,
                    "display_name": prof_name,
                    "xray_ready": xray_ready,
                    "singbox_ready": sb_ready,
                })

            if getattr(args, "json", False):
                res_data = {
                    "engines": engine_status,
                    "profiles": profile_readiness,
                }
                out_stream.write(json.dumps(res_data, indent=2) + "\n")
            else:
                lines: list[str] = []
                lines.append("ConnScope Environment & Protocol Readiness Check")
                lines.append("=" * 80)
                lines.append("Engine Binaries:")
                for eid, ed in engine_status.items():
                    if ed["binary"] is None:
                        lines.append(f"  - {eid:<12} ({ed['display_name']}): No binary required [Status: CATALOGUED]")
                    elif ed["is_ready"]:
                        lines.append(f"  - {eid:<12} ({ed['display_name']}): READY -> {ed['path']} (v{ed['version']})")
                    else:
                        lines.append(f"  - {eid:<12} ({ed['display_name']}): NOT AVAILABLE (binary '{ed['binary']}' not found)")

                lines.append("")
                lines.append("Executable Protocol Profiles:")
                lines.append(f"{'PROFILE ID':<24} {'DISPLAY NAME':<34} {'XRAY':<10} {'SING-BOX':<10}")
                lines.append("-" * 80)
                for pr in profile_readiness:
                    xr_str = "READY" if pr["xray_ready"] else "UNAVAILABLE"
                    sb_str = "READY" if pr["singbox_ready"] else "UNAVAILABLE"
                    lines.append(f"{pr['profile_id']:<24} {pr['display_name']:<34} {xr_str:<10} {sb_str:<10}")

                lines.append("")
                lines.append("Quick-Start Measurement Commands:")
                lines.append("  * Preview planned scenario (dry-run):")
                lines.append("      connscope matrix preview --engine xray --profile vless_tcp_none")
                lines.append("  * Execute local diagnostic measurement (VLESS over loopback, verified data transfer):")
                lines.append("      connscope matrix run --engine xray --profile vless_tcp_none --local-diagnostic --execute")
                lines.append("  * Execute against operator-supplied endpoint:")
                lines.append("      connscope matrix run --engine xray --profile vless_tcp_reality --target <host:port> --config <json> --execute")
                lines.append("")
                out_stream.write("\n".join(lines) + "\n")
            return ExitCode.OK

        err_stream.write(render_error(f"Unknown catalog subcommand '{cat_cmd}'") + "\n")
        return ExitCode.USAGE_ERROR

    if args.command == "matrix":
        mat_cmd = getattr(args, "matrix_command", None)
        if mat_cmd is None:
            err_stream.write(render_error("Missing matrix subcommand. Use 'connscope matrix preview' or 'estimate'.") + "\n")
            return ExitCode.USAGE_ERROR

        cat_path = getattr(args, "catalog", None)
        if cat_path:
            if not os.path.isfile(cat_path):
                err_stream.write(render_error(f"Catalog file not found: '{cat_path}'") + "\n")
                return ExitCode.USAGE_ERROR
            try:
                catalog = ProtocolCatalog.from_json_file(cat_path)
            except Exception as exc:
                err_stream.write(render_error(f"Failed to parse catalog JSON file: {exc}") + "\n")
                return ExitCode.USAGE_ERROR
        else:
            catalog = create_default_protocol_catalog()

        engine_filter = getattr(args, "engine", None)
        profile_filter = getattr(args, "profile", None)
        variant_filter = getattr(args, "variant", None)
        mode_str = getattr(args, "mode", "explicit")
        try:
            mode = GenerationMode(mode_str)
        except ValueError:
            err_stream.write(render_error(f"Invalid generation mode '{mode_str}'") + "\n")
            return ExitCode.USAGE_ERROR

        local_diag = getattr(args, "local_diagnostic", False)
        if local_diag:
            if not profile_filter:
                profile_filter = "vless_tcp_none"
            if not engine_filter:
                engine_filter = "xray"

        if engine_filter:
            if not catalog.get_engine(engine_filter):
                err_stream.write(render_error(f"Unknown engine '{engine_filter}' in catalog") + "\n")
                return ExitCode.USAGE_ERROR
            engine_ids = [engine_filter]
        else:
            engine_ids = [e.engine_id for e in catalog.list_engines()]

        if profile_filter:
            if not catalog.get_profile(profile_filter):
                err_stream.write(render_error(f"Unknown profile '{profile_filter}' in catalog") + "\n")
                return ExitCode.USAGE_ERROR
            profile_ids = [profile_filter]
        else:
            profile_ids = [p.profile_id for p in catalog.list_profiles()]

        variant_ids = [variant_filter] if variant_filter else None

        generator = ScenarioGenerator(
            catalog=catalog,
            max_scenarios=getattr(args, "max_scenarios", 100),
            allow_exhaustive=getattr(args, "allow_exhaustive", False),
        )

        if mat_cmd == "estimate":
            count = generator.estimate_count(engine_ids, profile_ids, variant_ids, mode)
            if getattr(args, "json", False):
                out_stream.write(
                    json.dumps(
                        {
                            "mode": mode.value,
                            "estimated_scenarios": count,
                            "engines": engine_ids,
                            "profiles": profile_ids,
                            "variants": variant_ids,
                        },
                        indent=2,
                    )
                    + "\n"
                )
            else:
                out_stream.write(
                    f"Estimated scenarios: {count} (Mode: {mode.value}, Engines: {len(engine_ids)}, Profiles: {len(profile_ids)})\n"
                )
            return ExitCode.OK

        if mat_cmd == "preview":
            target_str = getattr(args, "target", "127.0.0.1:443")
            try:
                target = parse_target(target_str)
                if target.port is None:
                    target = Target(host=target.host, port=443)
            except Exception as exc:
                err_stream.write(render_error(f"Invalid target '{target_str}': {exc}") + "\n")
                return ExitCode.USAGE_ERROR

            node_id = getattr(args, "node", None)
            node = catalog.get_node(node_id) if node_id else (catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost"))
            if not node:
                err_stream.write(render_error(f"Unknown measurement node '{node_id}' in catalog") + "\n")
                return ExitCode.USAGE_ERROR

            param_overrides: dict[str, Any] = {}
            if getattr(args, "config", None):
                raw_cfg = args.config.strip()
                if os.path.isfile(raw_cfg):
                    try:
                        with open(raw_cfg, "r", encoding="utf-8") as f:
                            param_overrides = json.load(f)
                    except Exception as exc:
                        err_stream.write(render_error(f"Failed to read config file: {exc}") + "\n")
                        return ExitCode.USAGE_ERROR
                else:
                    try:
                        param_overrides = json.loads(raw_cfg)
                    except Exception as exc:
                        err_stream.write(render_error(f"Invalid JSON in --config: {exc}") + "\n")
                        return ExitCode.USAGE_ERROR
                if not isinstance(param_overrides, dict):
                    err_stream.write(render_error("--config must resolve to a JSON object (dictionary)") + "\n")
                    return ExitCode.USAGE_ERROR

            if local_diag:
                param_overrides.setdefault("uuid", DEFAULT_DIAGNOSTIC_UUID)

            test_url = getattr(args, "test_url", None) or param_overrides.pop("test_url", None) or "http://cp.cloudflare.com/generate_204"
            timeout_s = getattr(args, "timeout", None) or param_overrides.pop("timeout_s", None) or param_overrides.pop("timeout", None) or 10.0
            reps_override = getattr(args, "repetitions", None) or param_overrides.pop("repetitions", None)
            workload = MeasurementWorkload(test_url=str(test_url), timeout_s=float(timeout_s), repetitions=int(reps_override) if reps_override else 1)

            try:
                match mode:
                    case GenerationMode.EXPLICIT:
                        plan = generator.generate_explicit(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            variant_ids=variant_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            parameter_overrides=param_overrides,
                        )
                    case GenerationMode.OFAT:
                        plan = generator.generate_ofat(
                            engine_id=engine_ids[0],
                            profile_id=profile_ids[0],
                            baseline_variant_id=variant_ids[0] if variant_ids else "baseline",
                            target=target,
                            node=node,
                            workload=workload,
                            baseline_overrides=param_overrides,
                        )
                    case GenerationMode.PAIRWISE:
                        plan = generator.generate_pairwise(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            base_overrides=param_overrides,
                        )
                    case GenerationMode.EXHAUSTIVE:
                        plan = generator.generate_exhaustive(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            variant_ids=variant_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            parameter_overrides=param_overrides,
                        )
            except MatrixSizeExceededError as exc:
                err_stream.write(render_error(str(exc)) + "\n")
                return ExitCode.USAGE_ERROR
            except Exception as exc:
                err_stream.write(render_error(f"Failed to generate scenario matrix: {exc}") + "\n")
                return ExitCode.INTERNAL_ERROR

            if getattr(args, "json", False):
                out_stream.write(render_scenario_matrix_json(plan) + "\n")
            else:
                out_stream.write(render_scenario_matrix_table(plan, catalog=catalog) + "\n")
            return ExitCode.OK

        if mat_cmd == "run":
            target_str = getattr(args, "target", "127.0.0.1:443")
            try:
                target = parse_target(target_str)
                if target.port is None:
                    target = Target(host=target.host, port=443)
            except Exception as exc:
                err_stream.write(render_error(f"Invalid target '{target_str}': {exc}") + "\n")
                return ExitCode.USAGE_ERROR

            node_id = getattr(args, "node", None)
            node = catalog.get_node(node_id) if node_id else (catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost"))
            if not node:
                err_stream.write(render_error(f"Unknown measurement node '{node_id}' in catalog") + "\n")
                return ExitCode.USAGE_ERROR

            param_overrides = {}
            if getattr(args, "config", None):
                raw_cfg = args.config.strip()
                if os.path.isfile(raw_cfg):
                    try:
                        with open(raw_cfg, "r", encoding="utf-8") as f:
                            param_overrides = json.load(f)
                    except Exception as exc:
                        err_stream.write(render_error(f"Failed to read config file: {exc}") + "\n")
                        return ExitCode.USAGE_ERROR
                else:
                    try:
                        param_overrides = json.loads(raw_cfg)
                    except Exception as exc:
                        err_stream.write(render_error(f"Invalid JSON in --config: {exc}") + "\n")
                        return ExitCode.USAGE_ERROR
                if not isinstance(param_overrides, dict):
                    err_stream.write(render_error("--config must resolve to a JSON object (dictionary)") + "\n")
                    return ExitCode.USAGE_ERROR

            local_diag = bool(getattr(args, "local_diagnostic", False))
            if local_diag:
                param_overrides.setdefault("uuid", DEFAULT_DIAGNOSTIC_UUID)

            test_url = getattr(args, "test_url", None) or param_overrides.pop("test_url", None) or "http://cp.cloudflare.com/generate_204"
            timeout_s = getattr(args, "timeout", None) or param_overrides.pop("timeout_s", None) or param_overrides.pop("timeout", None) or 10.0
            reps_override = getattr(args, "repetitions", None) or param_overrides.pop("repetitions", None)
            workload = MeasurementWorkload(test_url=str(test_url), timeout_s=float(timeout_s), repetitions=int(reps_override) if reps_override else 1)

            try:
                match mode:
                    case GenerationMode.EXPLICIT:
                        plan = generator.generate_explicit(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            variant_ids=variant_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            parameter_overrides=param_overrides,
                        )
                    case GenerationMode.OFAT:
                        plan = generator.generate_ofat(
                            engine_id=engine_ids[0],
                            profile_id=profile_ids[0],
                            baseline_variant_id=variant_ids[0] if variant_ids else "baseline",
                            target=target,
                            node=node,
                            workload=workload,
                            baseline_overrides=param_overrides,
                        )
                    case GenerationMode.PAIRWISE:
                        plan = generator.generate_pairwise(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            base_overrides=param_overrides,
                        )
                    case GenerationMode.EXHAUSTIVE:
                        plan = generator.generate_exhaustive(
                            engine_ids=engine_ids,
                            profile_ids=profile_ids,
                            variant_ids=variant_ids,
                            target=target,
                            node=node,
                            workload=workload,
                            parameter_overrides=param_overrides,
                        )
            except MatrixSizeExceededError as exc:
                err_stream.write(render_error(str(exc)) + "\n")
                return ExitCode.USAGE_ERROR
            except Exception as exc:
                err_stream.write(render_error(f"Failed to generate scenario matrix: {exc}") + "\n")
                return ExitCode.INTERNAL_ERROR

            execute_flag = bool(getattr(args, "execute", False))
            concurrency = getattr(args, "concurrency", 1)
            fail_policy_str = getattr(args, "failure_policy", "continue")
            try:
                fail_policy = FailurePolicy(fail_policy_str)
            except ValueError:
                err_stream.write(render_error(f"Invalid failure policy '{fail_policy_str}'") + "\n")
                return ExitCode.USAGE_ERROR

            def progress_reporter(event: dict[str, Any]) -> None:
                if not getattr(args, "json", False) and execute_flag:
                    etype = event.get("type")
                    if etype == "repetition_start":
                        err_stream.write(f"[{event['scenario_id']}] Repetition {event['repetition_index'] + 1}/{event['total_repetitions']} running...\n")
                    elif etype == "repetition_complete":
                        err_stream.write(f"[{event['scenario_id']}] Repetition {event['repetition_index'] + 1}: {event['status'].upper()} ({event['duration_ms']:.1f}ms)\n")

            coordinator = ScenarioCoordinator(
                catalog=catalog,
                concurrency=concurrency,
                failure_policy=fail_policy,
                progress_callback=progress_reporter,
            )

            if execute_flag and local_diag:
                diag_engine = engine_ids[0] if engine_ids else "xray"
                with LocalDiagnosticHarness(engine_id=diag_engine) as harness:
                    new_scenarios = []
                    for scn in plan.scenarios:
                        new_cfg = dict(scn.resolved_config)
                        new_cfg["endpoint"] = f"{harness.target.host}:{harness.target.port}"
                        new_cfg["test_url"] = harness.test_url
                        new_wl = replace(scn.workload, test_url=harness.test_url)
                        new_meta = dict(scn.metadata)
                        new_meta["diagnostic"] = True
                        new_scn = replace(
                            scn,
                            target=harness.target,
                            workload=new_wl,
                            resolved_config=new_cfg,
                            status=VerificationStatus.LOCAL_DIAGNOSTIC_VERIFIED,
                            metadata=new_meta,
                        )
                        new_scenarios.append(new_scn)
                    exec_plan = replace(plan, scenarios=tuple(new_scenarios))
                    result = asyncio.run(coordinator.execute_plan(
                        plan=exec_plan,
                        execute=True,
                        repetitions_override=reps_override,
                    ))
            else:
                result = asyncio.run(coordinator.execute_plan(
                    plan=plan,
                    execute=execute_flag,
                    repetitions_override=reps_override,
                ))

            out_file = getattr(args, "output_file", None)
            if out_file and result.records:
                try:
                    write_jsonl(result.records, out_file)
                except Exception as exc:
                    err_stream.write(render_error(f"Failed to write JSONL records to '{out_file}': {exc}") + "\n")
                    return ExitCode.INTERNAL_ERROR

            sum_file = getattr(args, "summary_file", None)
            if sum_file:
                try:
                    with open(sum_file, "w", encoding="utf-8") as f:
                        f.write(render_execution_summary_json(result.summary) + "\n")
                except Exception as exc:
                    err_stream.write(render_error(f"Failed to write summary JSON to '{sum_file}': {exc}") + "\n")
                    return ExitCode.INTERNAL_ERROR

            if getattr(args, "json", False):
                out_stream.write(render_execution_summary_json(result.summary) + "\n")
            else:
                if not execute_flag:
                    if local_diag:
                        out_stream.write("Planning mode only (dry-run) for local diagnostic harness. 0 processes spawned. Pass --execute to run measurements.\n\n")
                    else:
                        out_stream.write("Planning mode only (dry-run). 0 processes spawned. Pass --execute to run measurements.\n\n")
                out_stream.write(render_execution_summary_table(result.summary) + "\n")

            if not execute_flag:
                return ExitCode.OK

            if result.summary.failed_scenarios > 0:
                return ExitCode.FAILED
            return ExitCode.OK

        if mat_cmd == "coverage":
            report = generate_coverage_report(
                catalog,
                engine_filter=getattr(args, "engine", None),
                protocol_filter=getattr(args, "protocol", None),
                category_filter=getattr(args, "category", None),
            )
            if getattr(args, "json", False):
                out_stream.write(render_coverage_json(report) + "\n")
            else:
                out_stream.write(render_coverage_table(report) + "\n")
            return ExitCode.OK

        if mat_cmd == "preview-parameters":
            engine_id = getattr(args, "engine", "xray") or "xray"
            profile_id = getattr(args, "profile", "vless_tcp_reality") or "vless_tcp_reality"
            strategy = getattr(args, "strategy", "ofat") or "ofat"
            include_invalid = getattr(args, "include_invalid", False)

            target_str = getattr(args, "target", "127.0.0.1:443")
            try:
                target = parse_target(target_str)
                if target.port is None:
                    target = Target(host=target.host, port=443)
            except Exception as exc:
                err_stream.write(render_error(f"Invalid target '{target_str}': {exc}") + "\n")
                return ExitCode.USAGE_ERROR

            node_id = getattr(args, "node", None)
            node = catalog.get_node(node_id) if node_id else (catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost"))

            generator = ScenarioGenerator(catalog=catalog)
            try:
                plan = generator.generate_parameter_matrix(
                    engine_id=engine_id,
                    profile_id=profile_id,
                    strategy=strategy,
                    target=target,
                    node=node,
                    include_invalid=include_invalid,
                )
            except Exception as exc:
                err_stream.write(render_error(f"Parameter scenario generation failed: {exc}") + "\n")
                return ExitCode.USAGE_ERROR

            if getattr(args, "json", False):
                out_stream.write(render_scenario_matrix_json(plan) + "\n")
            else:
                out_stream.write(render_scenario_matrix_table(plan) + "\n")
            return ExitCode.OK

        err_stream.write(render_error(f"Unknown matrix subcommand '{mat_cmd}'") + "\n")
        return ExitCode.USAGE_ERROR

    err_stream.write(render_error(f"Unknown command '{args.command}'") + "\n")
    return ExitCode.USAGE_ERROR

def cli_entry(
    argv: list[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    registry: ProbeRegistry | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    out_stream = stdout if stdout is not None else sys.stdout
    err_stream = stderr if stderr is not None else sys.stderr

    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser(stdout=out_stream, stderr=err_stream)

    try:
        args = parser.parse_args(argv)
    except ArgumentParserExit as exc:
        return exc.status
    except UsageError as exc:
        err_stream.write(render_error(str(exc)) + "\n")
        return ExitCode.USAGE_ERROR

    if args.command is None:
        parser.print_help(err_stream)
        return ExitCode.USAGE_ERROR

    token: str | None = None
    if "args" in locals():
        _, token = resolve_remote_config(
            getattr(args, "node", None),
            getattr(args, "token", None),
            env=env,
        )

    try:
        return _dispatch(args, out_stream, err_stream, registry=registry, env=env)
    except KeyboardInterrupt:
        err_stream.write("\nOperation cancelled by user.\n")
        return ExitCode.USAGE_ERROR
    except UsageError as exc:
        err_stream.write(safe_render_error(str(exc), token=token) + "\n")
        return ExitCode.USAGE_ERROR
    except ClientConfigurationError as exc:
        err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
        return ExitCode.USAGE_ERROR
    except RemoteTimeoutError as exc:
        err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
        return ExitCode.TIMEOUT
    except RemoteClientError as exc:
        err_stream.write(safe_render_error(format_remote_error(exc, token=token), token=token) + "\n")
        return ExitCode.FAILED
    except Exception as exc:
        err_stream.write(safe_render_error(f"Internal error: {exc}", token=token) + "\n")
        return ExitCode.INTERNAL_ERROR

def main() -> None:
    sys.exit(cli_entry())

if __name__ == "__main__":
    main()
