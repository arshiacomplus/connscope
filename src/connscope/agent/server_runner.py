import argparse
import asyncio
from dataclasses import dataclass, field
import logging
import math
import os
import signal
import sys
from typing import Callable, Mapping, Sequence

from .server import AgentServer, validate_loopback_host

logger = logging.getLogger("connscope.agent")

class ConfigurationError(ValueError):
    pass

@dataclass(frozen=True)
class RunnerConfig:

    host: str = "127.0.0.1"
    port: int = 8088
    auth_token: str = field(repr=False, default="")
    allow_private: bool = False
    max_concurrency: int = 10
    max_connections: int = 50
    read_timeout_s: float = 5.0
    max_probe_timeout_s: float = 60.0
    shutdown_grace_s: float = 10.0
    outer_timeout_slack_s: float = 5.0
    log_level: str = "INFO"

    def __repr__(self) -> str:
        return (
            f"RunnerConfig(host={self.host!r}, port={self.port}, "
            f"auth_token='[REDACTED]', allow_private={self.allow_private}, "
            f"max_concurrency={self.max_concurrency}, max_connections={self.max_connections}, "
            f"read_timeout_s={self.read_timeout_s}, max_probe_timeout_s={self.max_probe_timeout_s}, "
            f"shutdown_grace_s={self.shutdown_grace_s}, outer_timeout_slack_s={self.outer_timeout_slack_s}, "
            f"log_level={self.log_level!r})"
        )

def _parse_positive_int(env: Mapping[str, str], key: str, default: int) -> int:
    val_raw = env.get(key)
    if val_raw is None or not val_raw.strip():
        return default
    try:
        val = int(val_raw.strip())
    except ValueError:
        raise ConfigurationError(f"Invalid {key}: expected integer, got {val_raw!r}")
    if val <= 0:
        raise ConfigurationError(f"Invalid {key}: must be a positive integer, got {val}")
    return val

def _parse_positive_float(env: Mapping[str, str], key: str, default: float) -> float:
    val_raw = env.get(key)
    if val_raw is None or not val_raw.strip():
        return default
    try:
        val = float(val_raw.strip())
    except ValueError:
        raise ConfigurationError(f"Invalid {key}: expected float, got {val_raw!r}")
    if not math.isfinite(val) or val <= 0:
        raise ConfigurationError(f"Invalid {key}: must be a positive finite number, got {val}")
    return val

def _parse_non_negative_float(env: Mapping[str, str], key: str, default: float) -> float:
    val_raw = env.get(key)
    if val_raw is None or not val_raw.strip():
        return default
    try:
        val = float(val_raw.strip())
    except ValueError:
        raise ConfigurationError(f"Invalid {key}: expected float, got {val_raw!r}")
    if not math.isfinite(val) or val < 0:
        raise ConfigurationError(f"Invalid {key}: must be a non-negative finite number, got {val}")
    return val

def load_runner_config(env: Mapping[str, str] | None = None) -> RunnerConfig:
    if env is None:
        env = os.environ

    token_raw = env.get("CONNSCOPE_AUTH_TOKEN")
    if token_raw is None:
        raise ConfigurationError("Missing required environment variable: CONNSCOPE_AUTH_TOKEN")
    auth_token = token_raw.strip()
    if not auth_token:
        raise ConfigurationError("CONNSCOPE_AUTH_TOKEN must be a non-empty string")

    host_raw = env.get("CONNSCOPE_BIND_HOST", "127.0.0.1")
    try:
        host = validate_loopback_host(host_raw)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid CONNSCOPE_BIND_HOST: {exc}") from exc

    port_raw = env.get("CONNSCOPE_BIND_PORT", "8088")
    try:
        port = int(port_raw.strip())
    except (ValueError, AttributeError):
        raise ConfigurationError(f"Invalid CONNSCOPE_BIND_PORT: expected integer, got {port_raw!r}")
    if not (0 <= port <= 65535):
        raise ConfigurationError(f"Invalid CONNSCOPE_BIND_PORT: port must be between 0 and 65535, got {port}")

    allow_private_raw = env.get("CONNSCOPE_ALLOW_PRIVATE", "false").strip().lower()
    if allow_private_raw in ("true", "1", "yes"):
        allow_private = True
    elif allow_private_raw in ("false", "0", "no", ""):
        allow_private = False
    else:
        raise ConfigurationError(
            f"Invalid CONNSCOPE_ALLOW_PRIVATE: expected boolean (true/false/1/0), got {allow_private_raw!r}"
        )

    max_concurrency = _parse_positive_int(env, "CONNSCOPE_MAX_CONCURRENCY", 10)
    max_connections = _parse_positive_int(env, "CONNSCOPE_MAX_CONNECTIONS", 50)
    read_timeout_s = _parse_positive_float(env, "CONNSCOPE_READ_TIMEOUT_S", 5.0)
    max_probe_timeout_s = _parse_positive_float(env, "CONNSCOPE_MAX_PROBE_TIMEOUT_S", 60.0)
    shutdown_grace_s = _parse_non_negative_float(env, "CONNSCOPE_SHUTDOWN_GRACE_S", 10.0)
    outer_timeout_slack_s = _parse_non_negative_float(env, "CONNSCOPE_OUTER_TIMEOUT_SLACK_S", 5.0)

    log_level = env.get("CONNSCOPE_LOG_LEVEL", "INFO").strip().upper()
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ConfigurationError(
            f"Invalid CONNSCOPE_LOG_LEVEL: expected DEBUG, INFO, WARNING, ERROR, or CRITICAL, got {log_level!r}"
        )

    return RunnerConfig(
        host=host,
        port=port,
        auth_token=auth_token,
        allow_private=allow_private,
        max_concurrency=max_concurrency,
        max_connections=max_connections,
        read_timeout_s=read_timeout_s,
        max_probe_timeout_s=max_probe_timeout_s,
        shutdown_grace_s=shutdown_grace_s,
        outer_timeout_slack_s=outer_timeout_slack_s,
        log_level=log_level,
    )

def configure_logging(level: str = "INFO") -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] connscope.agent: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )

async def run_server(
    config: RunnerConfig,
    *,
    stop_event: asyncio.Event | None = None,
    ready_callback: Callable[[AgentServer], None] | None = None,
) -> None:
    server = AgentServer(
        host=config.host,
        port=config.port,
        auth_token=config.auth_token,
        allow_private=config.allow_private,
        max_concurrency=config.max_concurrency,
        max_connections=config.max_connections,
        read_timeout_s=config.read_timeout_s,
        max_probe_timeout_s=config.max_probe_timeout_s,
        shutdown_grace_s=config.shutdown_grace_s,
        outer_timeout_slack_s=config.outer_timeout_slack_s,
    )

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _on_signal(sig_num: int) -> None:
        try:
            sig_name = signal.Signals(sig_num).name
        except ValueError:
            sig_name = str(sig_num)
        logger.info("Received signal %s, initiating graceful shutdown...", sig_name)
        shutdown_event.set()

    installed_signals: list[int] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal, sig)
            installed_signals.append(sig)
        except (NotImplementedError, ValueError):
            pass

    forward_task: asyncio.Task[None] | None = None
    if stop_event is not None:

        async def _forward_stop() -> None:
            await stop_event.wait()
            shutdown_event.set()

        forward_task = asyncio.create_task(_forward_stop())

    try:
        async with server:
            logger.info(
                "Starting ConnScope agent on %s:%d (allow_private=%s, max_concurrency=%d)",
                server.host,
                server.port,
                server.allow_private,
                server.max_concurrency,
            )
            if ready_callback is not None:
                ready_callback(server)

            await shutdown_event.wait()
            logger.info("Shutting down ConnScope agent...")
    finally:
        if forward_task is not None and not forward_task.done():
            forward_task.cancel()
            try:
                await forward_task
            except asyncio.CancelledError:
                pass

        for sig in installed_signals:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, ValueError):
                pass

        logger.info("ConnScope agent server shut down successfully.")

def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="python -m connscope.agent.server_runner",
        description="ConnScope Agent Server Production Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment Variables:\n"
            "  CONNSCOPE_AUTH_TOKEN          Required authentication token for /v1/measure\n"
            "  CONNSCOPE_BIND_HOST           Loopback bind address (default: 127.0.0.1)\n"
            "  CONNSCOPE_BIND_PORT           Bind port (default: 8088)\n"
            "  CONNSCOPE_ALLOW_PRIVATE       Permit RFC 1918/4193 targets (default: false)\n"
            "  CONNSCOPE_MAX_CONCURRENCY     Max concurrent measurements (default: 10)\n"
            "  CONNSCOPE_MAX_CONNECTIONS     Max concurrent TCP connections (default: 50)\n"
            "  CONNSCOPE_READ_TIMEOUT_S      HTTP request read timeout in seconds (default: 5.0)\n"
            "  CONNSCOPE_MAX_PROBE_TIMEOUT_S Max probe execution timeout in seconds (default: 60.0)\n"
            "  CONNSCOPE_SHUTDOWN_GRACE_S    Shutdown grace period in seconds (default: 10.0)\n"
            "  CONNSCOPE_OUTER_TIMEOUT_SLACK_S Outer slack timeout in seconds (default: 5.0)\n"
            "  CONNSCOPE_LOG_LEVEL           Log level (default: INFO)\n"
        ),
    )
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code

    try:
        config = load_runner_config(env)
    except ConfigurationError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        return 1

    configure_logging(config.log_level)

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        sys.stderr.write(f"Fatal error running agent server: {exc}\n")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
