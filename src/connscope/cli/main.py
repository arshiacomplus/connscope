import argparse
import asyncio
from enum import IntEnum
import sys
from typing import Any, TextIO

from connscope.core import ProbeEngine, ProbeRegistry, ProbeStatus
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

    # connscope probe ...
    probe_parser = subparsers.add_parser("probe", help="Probe commands")
    probe_sub = probe_parser.add_subparsers(dest="probe_command")
    probe_sub.add_parser("list", help="List available builtin probes")

    # connscope list (alias for connscope probe list)
    subparsers.add_parser("list", help="List available builtin probes")

    # connscope run <probe> <target> [--timeout N]
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

    return parser


def _dispatch(
    args: argparse.Namespace,
    out_stream: TextIO,
    err_stream: TextIO,
    registry: ProbeRegistry | None = None,
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
        try:
            canonical = resolve_probe_name(args.probe, reg)
        except KeyError as exc:
            err_stream.write(render_error(str(exc)) + "\n")
            return ExitCode.USAGE_ERROR

        try:
            if canonical == "http_request":
                target, config = parse_http_target(args.target)
            else:
                target = parse_target(args.target)
                config = {}
        except ValueError as exc:
            err_stream.write(render_error(str(exc)) + "\n")
            return ExitCode.USAGE_ERROR

        if canonical == "tcp_connect" and target.port is None:
            err_stream.write(
                render_error(f"Target port is required for TCP probe: '{args.target}' (e.g. 'example.com:443')") + "\n"
            )
            return ExitCode.USAGE_ERROR

        if canonical == "dns_resolve" and target.port is not None:
            err_stream.write(
                render_error(f"Port is not supported for DNS probe: '{args.target}'") + "\n"
            )
            return ExitCode.USAGE_ERROR

        if args.timeout is not None:
            try:
                config["timeout_s"] = validate_timeout(args.timeout)
            except ValueError as exc:
                err_stream.write(render_error(str(exc)) + "\n")
                return ExitCode.USAGE_ERROR

        engine = ProbeEngine(registry=reg)
        result = asyncio.run(engine.run(canonical, target, config))
        if getattr(args, "json", False):
            out_str = render_result_json(result)
        else:
            out_str = render_result(result)
        out_stream.write(out_str + "\n")
        return STATUS_TO_EXIT_CODE.get(result.status, ExitCode.INTERNAL_ERROR)

    err_stream.write(render_error(f"Unknown command '{args.command}'") + "\n")
    return ExitCode.USAGE_ERROR


def cli_entry(
    argv: list[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    registry: ProbeRegistry | None = None,
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

    try:
        return _dispatch(args, out_stream, err_stream, registry=registry)
    except KeyboardInterrupt:
        err_stream.write("\nOperation cancelled by user.\n")
        return ExitCode.USAGE_ERROR
    except UsageError as exc:
        err_stream.write(render_error(str(exc)) + "\n")
        return ExitCode.USAGE_ERROR
    except Exception as exc:
        err_stream.write(f"Internal error: {exc}\n")
        return ExitCode.INTERNAL_ERROR


def main() -> None:
    sys.exit(cli_entry())


if __name__ == "__main__":
    main()
