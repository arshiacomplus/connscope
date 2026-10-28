from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Any, Sequence
import urllib.parse

from connscope.core import ProbeResult, ProbeStatus, Target
from .base import EngineAdapter
from .models import (
    AdapterCapability,
    AdapterMetadata,
    AdapterResultDetails,
    AdapterStatus,
    EngineType,
    ExecutableRequirement,
    FailureStage,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)
from .process import (
    find_free_loopback_port,
    read_bounded_stream,
    scrub_sensitive_text,
    terminate_process_tree,
    verify_tunnel_and_data_transfer,
    wait_for_proxy_ready,
)
from .security import (
    DEFAULT_OUTPUT_LIMIT_BYTES,
    redact_sensitive_data,
    resolve_safe_executable,
    safe_temporary_workspace,
    validate_command_args,
)
from .builders import (
    build_singbox_config,
    build_xray_config,
    get_profile_secrets,
    normalize_profile_keys,
    validate_profile_config,
)

class ProfileDrivenAdapter(EngineAdapter):
    def __init__(
        self,
        adapter_id: str,
        engine: EngineType | str,
        protocol: ProtocolType | str,
        transport: TransportType | str,
        security: SecurityType | str,
        display_name: str | None = None,
        min_version: str | None = None,
        lookup_paths: tuple[str, ...] | None = None,
        capabilities: frozenset[AdapterCapability] | None = None,
        status: AdapterStatus = AdapterStatus.REAL_ENGINE_INTEGRATION_TESTED,
        description: str = "",
    ) -> None:
        eng = EngineType(engine) if isinstance(engine, str) else engine
        proto = ProtocolType(protocol) if isinstance(protocol, str) else protocol
        trans = TransportType(transport) if isinstance(transport, str) else transport
        sec = SecurityType(security) if isinstance(security, str) else security

        bin_name = "xray" if eng == EngineType.XRAY else "sing-box"
        min_ver = min_version or ("1.8.0" if eng == EngineType.XRAY else "1.10.0")

        caps = capabilities or frozenset({
            AdapterCapability.TCP_CONNECT,
            AdapterCapability.HANDSHAKE,
            AdapterCapability.TUNNEL_VERIFY,
            AdapterCapability.DATA_TRANSFER,
            AdapterCapability.LATENCY,
        })

        lp = lookup_paths
        if lp is None:
            if eng == EngineType.SING_BOX:
                extra = [str(Path.home() / ".local/share/v2rayN/bin/sing_box"), str(Path.home() / "ACP-Portable/tools/proxy/bin")]
                existing_extra = [p for p in extra if os.path.isdir(p)]
                lp = ("/usr/local/bin", "/usr/bin", "/bin") + tuple(existing_extra)
            else:
                lp = ("/usr/local/bin", "/usr/bin", "/bin")

        self.metadata = AdapterMetadata(
            adapter_id=adapter_id,
            display_name=display_name or f"{eng.value.replace('_', '-')} {proto.value.upper()} {trans.value.upper()} {sec.value.upper()}",
            engine=eng,
            protocol=proto,
            transport=trans,
            security=sec,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=caps,
            status=status,
            executable=ExecutableRequirement(
                binary_name=bin_name,
                min_version=min_ver,
                lookup_paths=lp,
            ),
            description=description or f"Profile-driven {eng.value} adapter for {proto.value}/{trans.value}/{sec.value}",
        )

    def validate_target(self, target: Target) -> None:
        if not isinstance(target, Target):
            raise TypeError(f"Expected Target, got {type(target).__name__}")
        if not target.host or not isinstance(target.host, str) or not target.host.strip():
            raise ValueError("Target host must be a non-empty string")
        if target.port is None:
            raise ValueError("Target port is required")
        if isinstance(target.port, bool) or not isinstance(target.port, int) or not (1 <= target.port <= 65535):
            raise ValueError(f"Invalid target port: {target.port!r} (must be between 1 and 65535)")

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return validate_profile_config(
            self.metadata.protocol,
            self.metadata.transport,
            self.metadata.security,
            config,
            engine=self.metadata.engine,
        )

    def check_executable(self, lookup_paths: tuple[str, ...] | None = None) -> tuple[bool, str | None]:
        bin_name = self.metadata.executable.binary_name if self.metadata.executable else "unknown"
        paths = lookup_paths or (self.metadata.executable.lookup_paths if self.metadata.executable else None)
        try:
            exe_path = resolve_safe_executable(bin_name, lookup_paths=paths if paths is not None else DEFAULT_LOOKUP_PATHS)
            if exe_path:
                return True, exe_path
            return False, f"Executable '{bin_name}' not found in allowlisted paths"
        except Exception as exc:
            return False, str(exc)

    def generate_config(
        self,
        target: Target,
        config: dict[str, Any],
        local_socks_port: int,
        local_http_port: int,
        local_host: str = "127.0.0.1",
    ) -> dict[str, Any]:
        if self.metadata.engine == EngineType.XRAY:
            return build_xray_config(
                target=target,
                protocol=self.metadata.protocol,
                transport=self.metadata.transport,
                security=self.metadata.security,
                config=config,
                local_socks_port=local_socks_port,
                local_http_port=local_http_port,
                local_host=local_host,
            )
        return build_singbox_config(
            target=target,
            protocol=self.metadata.protocol,
            transport=self.metadata.transport,
            security=self.metadata.security,
            config=config,
            local_socks_port=local_socks_port,
            local_http_port=local_http_port,
            local_host=local_host,
        )

    def test_configuration(
        self,
        config: Path | str | dict[str, Any],
        secrets: Sequence[str] | None = None,
        target: Target | None = None,
        timeout_s: float = 5.0,
    ) -> tuple[bool, str]:
        ok, exe_or_reason = self.check_executable()
        if not ok or exe_or_reason is None:
            return False, f"Executable check failed: {exe_or_reason}"

        executable = exe_or_reason

        if isinstance(config, (str, Path)):
            config_file = Path(config)
            all_secrets = list(secrets or [])
            if self.metadata.engine == EngineType.XRAY:
                cmd = [executable, "run", "-test", "-c", str(config_file)]
            else:
                cmd = [executable, "check", "-c", str(config_file)]
            validate_command_args(cmd)
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_s,
                    text=True,
                )
                raw_out = (proc.stdout or "").strip()
                raw_err = (proc.stderr or "").strip()
                combined = f"{raw_out}\n{raw_err}".strip()
                if proc.returncode == 0:
                    return True, raw_out or "Configuration OK."
                clean_err = scrub_sensitive_text(combined, all_secrets)
                return False, clean_err or f"Config test failed with exit code {proc.returncode}"
            except subprocess.TimeoutExpired:
                return False, f"Config test timed out after {timeout_s:.1f}s"
            except Exception as exc:
                clean_err = scrub_sensitive_text(str(exc), all_secrets)
                return False, f"Config test failed: {clean_err}"

        eff_target = target or Target(host="127.0.0.1", port=443)
        try:
            val_cfg = self.validate_config(config)
        except Exception as exc:
            return False, f"Configuration validation failed: {exc}"

        all_secrets = list(secrets or []) + get_profile_secrets(val_cfg)

        with safe_temporary_workspace() as ws_dir:
            config_file = ws_dir / "config.json"
            native_cfg = self.generate_config(
                target=eff_target,
                config=val_cfg,
                local_socks_port=find_free_loopback_port(),
                local_http_port=find_free_loopback_port(),
            )
            config_file.write_text(json.dumps(native_cfg, indent=2), encoding="utf-8")

            if self.metadata.engine == EngineType.XRAY:
                cmd = [executable, "run", "-test", "-c", str(config_file)]
            else:
                cmd = [executable, "check", "-c", str(config_file)]
            validate_command_args(cmd)

            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_s,
                    text=True,
                )
                raw_out = (proc.stdout or "").strip()
                raw_err = (proc.stderr or "").strip()
                combined = f"{raw_out}\n{raw_err}".strip()
                if proc.returncode == 0:
                    return True, raw_out or "Configuration OK."
                clean_err = scrub_sensitive_text(combined, all_secrets)
                return False, clean_err or f"Config test failed with exit code {proc.returncode}"
            except subprocess.TimeoutExpired:
                return False, f"Config test timed out after {timeout_s:.1f}s"
            except Exception as exc:
                clean_err = scrub_sensitive_text(str(exc), all_secrets)
                return False, f"Config test failed: {clean_err}"

    def _get_wait_for_proxy_ready(self):
        mod = sys.modules.get(self.__class__.__module__)
        if mod and hasattr(mod, "wait_for_proxy_ready"):
            return getattr(mod, "wait_for_proxy_ready")
        return wait_for_proxy_ready

    def _get_verify_tunnel_and_data_transfer(self):
        mod = sys.modules.get(self.__class__.__module__)
        if mod and hasattr(mod, "verify_tunnel_and_data_transfer"):
            return getattr(mod, "verify_tunnel_and_data_transfer")
        return verify_tunnel_and_data_transfer

    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()

        try:
            self.validate_target(target)
            validated_config = self.validate_config(config)
        except (ValueError, TypeError) as exc:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return self.create_failure_result(
                target=target,
                started_at=started_at,
                duration_ms=duration_ms,
                failure_stage=FailureStage.CONFIG_GENERATION,
                error=f"Configuration error: {exc}",
                extra={"redacted_config": redact_sensitive_data(config or {})},
            )

        timeout_s = validated_config["timeout_s"]
        startup_timeout_s = validated_config["startup_timeout_s"]
        test_url = validated_config["test_url"]
        verify_cert = validated_config["verify_cert"]
        ssl_context = validated_config.get("ssl_context")

        secrets = get_profile_secrets(validated_config)
        if config:
            for k, v in config.items():
                if isinstance(v, str) and any(
                    s in k.lower() for s in ("password", "key", "token", "secret", "psk")
                ):
                    secrets.append(v)

        ok, exe_or_reason = self.check_executable()
        if not ok or exe_or_reason is None:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            return self.create_failure_result(
                target=target,
                started_at=started_at,
                duration_ms=duration_ms,
                failure_stage=FailureStage.PRE_FLIGHT,
                error=str(exe_or_reason),
                extra={"redacted_config": redact_sensitive_data(validated_config)},
            )
        executable = exe_or_reason

        max_attempts = 3 if validated_config.get("local_port") is None else 1
        socks_port: int = 0
        http_port: int = 0

        for attempt in range(max_attempts):
            try:
                socks_port = validated_config.get("local_port") or find_free_loopback_port()
                http_port = find_free_loopback_port()
                while http_port == socks_port:
                    http_port = find_free_loopback_port()
            except OSError as exc:
                duration_ms = (time.monotonic() - start_time) * 1000.0
                return self.create_failure_result(
                    target=target,
                    started_at=started_at,
                    duration_ms=duration_ms,
                    failure_stage=FailureStage.PROCESS_SPAWN,
                    error=f"Failed to allocate local ports: {exc}",
                    extra={"redacted_config": redact_sensitive_data(validated_config)},
                )

            try:
                with safe_temporary_workspace() as ws_dir:
                    config_file = ws_dir / "config.json"
                    native_cfg = self.generate_config(
                        target=target,
                        config=validated_config,
                        local_socks_port=socks_port,
                        local_http_port=http_port,
                    )
                    config_file.write_text(json.dumps(native_cfg, indent=2), encoding="utf-8")

                    cmd = [executable, "run", "-c", str(config_file)]
                    validate_command_args(cmd)

                    t_spawn_start = time.monotonic()
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            start_new_session=True,
                        )
                    except (FileNotFoundError, PermissionError, OSError) as exc:
                        duration_ms = (time.monotonic() - start_time) * 1000.0
                        return self.create_failure_result(
                            target=target,
                            started_at=started_at,
                            duration_ms=duration_ms,
                            failure_stage=FailureStage.PROCESS_SPAWN,
                            error=f"Failed to spawn process: {exc}",
                            extra={"redacted_config": redact_sensitive_data(validated_config)},
                        )

                    wait_fn = self._get_wait_for_proxy_ready()
                    is_ready = await wait_fn(
                        "127.0.0.1",
                        socks_port,
                        proc,
                        timeout_s=startup_timeout_s,
                    )

                    if not is_ready:
                        await terminate_process_tree(proc)
                        stdout_bytes = await read_bounded_stream(proc.stdout)
                        stderr_bytes = await read_bounded_stream(proc.stderr)

                        raw_err = (stderr_bytes or stdout_bytes).decode("utf-8", errors="replace").strip()
                        clean_err = scrub_sensitive_text(raw_err, secrets)
                        exit_code = proc.returncode
                        last_error = clean_err or f"Process failed to start (exit code {exit_code})"
                        last_exit_code = exit_code

                        if attempt < max_attempts - 1:
                            continue

                        duration_ms = (time.monotonic() - start_time) * 1000.0
                        return self.create_failure_result(
                            target=target,
                            started_at=started_at,
                            duration_ms=duration_ms,
                            failure_stage=FailureStage.PROCESS_SPAWN,
                            error=last_error,
                            extra={
                                "exit_code": last_exit_code,
                                "redacted_config": redact_sensitive_data(validated_config),
                            },
                        )

                    ready_ms = (time.monotonic() - t_spawn_start) * 1000.0
                    elapsed_so_far = time.monotonic() - start_time
                    rem_timeout = max(0.5, timeout_s - elapsed_so_far)

                    verify_fn = self._get_verify_tunnel_and_data_transfer()
                    try:
                        v_result = await verify_fn(
                            proxy_host="127.0.0.1",
                            proxy_port=socks_port,
                            test_url=test_url,
                            timeout_s=rem_timeout,
                            verify_cert=verify_cert,
                            ssl_context=ssl_context,
                        )
                    except asyncio.CancelledError:
                        await terminate_process_tree(proc)
                        raise
                    finally:
                        await terminate_process_tree(proc)

                    duration_ms = (time.monotonic() - start_time) * 1000.0
                    metrics: dict[str, float] = {
                        "local_ready_ms": ready_ms,
                        "handshake_ms": v_result.handshake_ms,
                        "data_transfer_ms": v_result.data_transfer_ms,
                        "total_ms": duration_ms,
                    }
                    if v_result.tls_handshake_ms > 0:
                        metrics["tls_handshake_ms"] = v_result.tls_handshake_ms

                    is_https = test_url.startswith("https://")
                    tls_mode = "enforced" if verify_cert else "disabled"

                    if v_result.data_transfer_completed:
                        failure_stage = None
                        verified_data_transfer = bool(v_result.tls_verified) if is_https else True
                    else:
                        verified_data_transfer = False
                        if not v_result.tunnel_established:
                            failure_stage = FailureStage.HANDSHAKE
                        elif is_https and (
                            v_result.tls_verified is False
                            or (v_result.error_message and "tls" in v_result.error_message.lower())
                        ):
                            failure_stage = FailureStage.HANDSHAKE
                        else:
                            failure_stage = FailureStage.DATA_TRANSFER

                    details = AdapterResultDetails(
                        adapter_id=self.metadata.adapter_id,
                        engine=self.metadata.engine.value,
                        protocol=self.metadata.protocol.value,
                        transport=self.metadata.transport.value,
                        security=self.metadata.security.value,
                        tunnel_established=v_result.tunnel_established,
                        data_transfer_completed=v_result.data_transfer_completed,
                        failure_stage=failure_stage,
                        extra={
                            "local_port": socks_port,
                            "local_socks_port": socks_port,
                            "local_http_port": http_port,
                            "http_status": v_result.http_status,
                            "test_url": test_url,
                            "verify_cert": verify_cert,
                            "tls_verified": v_result.tls_verified,
                            "tls_verification_mode": tls_mode,
                            "verified_data_transfer": verified_data_transfer,
                            "redacted_config": redact_sensitive_data(validated_config),
                        },
                    )

                    if v_result.data_transfer_completed:
                        return self.create_result(
                            target=target,
                            status=ProbeStatus.SUCCESS,
                            started_at=started_at,
                            duration_ms=duration_ms,
                            details=details,
                            metrics=metrics,
                        )

                    clean_verr = scrub_sensitive_text(v_result.error_message or "Tunnel verification failed", secrets)
                    return self.create_result(
                        target=target,
                        status=ProbeStatus.FAILED,
                        started_at=started_at,
                        duration_ms=duration_ms,
                        details=details,
                        metrics=metrics,
                        error=clean_verr,
                    )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                duration_ms = (time.monotonic() - start_time) * 1000.0
                clean_err = scrub_sensitive_text(str(exc), secrets)
                return self.create_failure_result(
                    target=target,
                    started_at=started_at,
                    duration_ms=duration_ms,
                    failure_stage=FailureStage.PROCESS_SPAWN,
                    error=f"Unexpected error: {clean_err}",
                    extra={"redacted_config": redact_sensitive_data(validated_config)},
                )

        duration_ms = (time.monotonic() - start_time) * 1000.0
        return self.create_failure_result(
            target=target,
            started_at=started_at,
            duration_ms=duration_ms,
            failure_stage=FailureStage.PROCESS_SPAWN,
            error="Failed to allocate and bind proxy ports after retries",
            extra={"redacted_config": redact_sensitive_data(validated_config)},
        )
